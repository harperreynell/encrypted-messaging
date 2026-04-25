#ifndef SWT_THREADPOOL_H
#define SWT_THREADPOOL_H

#include <vector>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <atomic>
#include <chrono>
#include <iostream>
#include <algorithm>

struct TaskMetadata {
    std::chrono::steady_clock::time_point arrival_time;
    std::chrono::steady_clock::time_point start_time;
};

class ThreadPool {
public:
    ThreadPool(size_t threads, size_t max_q = 50)
        : stop(false), max_queue_size(max_q), created_threads(threads) {

        for (size_t i = 0; i < threads; ++i) {
            workers.emplace_back([this, i] {
                while (true) {
                    std::function<void()> task;
                    TaskMetadata meta;
                    auto wait_start = std::chrono::steady_clock::now();

                    {
                        std::unique_lock<std::mutex> lock(this->queue_mutex);
                        this->condition.wait(lock, [this] {
                            return this->stop || !this->tasks.empty();
                        });

                        auto wait_end = std::chrono::steady_clock::now();
                        total_idle_time += std::chrono::duration_cast<std::chrono::microseconds>(wait_end - wait_start).count();

                        if (this->stop && this->tasks.empty()) return;

                        task = std::move(this->tasks.front().first);
                        meta = this->tasks.front().second;
                        this->tasks.pop();

                        size_t current_q = tasks.size();
                        queue_sum += current_q;
                        queue_samples++;

                        if (current_q < max_queue_size && queue_full_start != std::chrono::steady_clock::time_point()) {
                            auto full_duration = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - queue_full_start).count();
                            max_full_time = std::max(max_full_time, full_duration);
                            min_full_time = (min_full_time == 0) ? full_duration : std::min(min_full_time, full_duration);
                            queue_full_start = std::chrono::steady_clock::time_point();
                        }
                    }

                    meta.start_time = std::chrono::steady_clock::now();
                    total_wait_time += std::chrono::duration_cast<std::chrono::microseconds>(meta.start_time - meta.arrival_time).count();

                    task();

                    auto end_time = std::chrono::steady_clock::now();
                    total_exec_time += std::chrono::duration_cast<std::chrono::microseconds>(end_time - meta.start_time).count();
                    completed_tasks++;
                }
            });
        }
    }

    template<class F>
    bool enqueue(F&& f) {
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            if (tasks.size() >= max_queue_size) {
                dropped_tasks++;
                if (queue_full_start == std::chrono::steady_clock::time_point()) {
                    queue_full_start = std::chrono::steady_clock::now();
                }
                return false;
            }

            TaskMetadata meta;
            meta.arrival_time = std::chrono::steady_clock::now();
            tasks.emplace(std::forward<F>(f), meta);

            queue_sum += tasks.size();
            queue_samples++;
        }
        condition.notify_one();
        return true;
    }

    void printStats() {
        std::cout << "\n--- Thread Pool Statistics ---\n";
        std::cout << "Threads created: " << created_threads << "\n";
        std::cout << "Tasks completed: " << completed_tasks << "\n";
        std::cout << "Tasks dropped: " << dropped_tasks << "\n";

        if (completed_tasks > 0) {
            std::cout << "Avg task wait in queue: " << (total_wait_time / completed_tasks) / 1000.0 << " ms\n";
            std::cout << "Avg task exec time: " << (total_exec_time / completed_tasks) / 1000.0 << " ms\n";
        }

        std::cout << "Avg thread idle time: " << (total_idle_time / created_threads) / 1000.0 << " ms\n";

        if (queue_samples > 0) {
            std::cout << "Avg queue length: " << (double)queue_sum / queue_samples << "\n";
        }

        std::cout << "Max time queue was full: " << max_full_time / 1000.0 << " ms\n";
        std::cout << "Min time queue was full: " << min_full_time / 1000.0 << " ms\n";
        std::cout << "----------------------------\n";
    }

    ~ThreadPool() {
        stop = true;
        condition.notify_all();
        for (std::thread &worker : workers) worker.join();
    }

private:
    std::vector<std::thread> workers;
    std::queue<std::pair<std::function<void()>, TaskMetadata>> tasks;
    std::mutex queue_mutex;
    std::condition_variable condition;
    std::atomic<bool> stop;

    size_t max_queue_size;
    size_t created_threads;
    std::atomic<size_t> completed_tasks{0};
    std::atomic<size_t> dropped_tasks{0};

    std::atomic<long long> total_wait_time{0};
    std::atomic<long long> total_exec_time{0};
    std::atomic<long long> total_idle_time{0};

    std::atomic<long long> queue_sum{0};
    std::atomic<long long> queue_samples{0};

    std::chrono::steady_clock::time_point queue_full_start;
    long long max_full_time{0};
    long long min_full_time{0};
};

#endif