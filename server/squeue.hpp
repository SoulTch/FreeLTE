#ifndef _SQUEUE_H__
#define _SQUEUE_H__

#include <queue>
#include <mutex>

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


#endif