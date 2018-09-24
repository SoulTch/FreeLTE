#ifndef _SQUEUE_H__
#define _SQUEUE_H__

#include <queue>
#include <mutex>
#include <condition_variable>

template <typename T>
class Squeue{
public:
    T pop();
    void push(const T&);
private:
    std::queue<T> queue_;
    std::mutex mutex_;
    std::condition_variable cond_;
};

template <typename T>
T Squeue<T>::pop() {
    std::unique_lock<std::mutex> mlock(mutex_);
    while(queue_.empty()) {
        cond_.wait(mlock);
    }
    T item = queue_.front();
    queue_.pop();
    mlock.unlock();
    return item;
}

template <typename T>
void Squeue<T>::push(const T& item) {
    std::unique_lock<std::mutex> mlock(mutex_);
    queue_.push(item);
    mlock.unlock();
    cond_.notify_one();
}

#endif
