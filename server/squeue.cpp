#include "squeue.hpp"

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