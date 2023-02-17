/*
 * An array class having interfaces similar to vector but has static memory and semi-atomic push.
 * Author: Pavinberg
 */

#ifndef BESS_UTILS_YARRAY_H_
#define BESS_UTILS_YARRAY_H_

#include <cstdint>
#include <atomic>

#define MAX_SIZE 256

namespace bess {
namespace utils {

template <typename T>
class Yarray {
 public:
  Yarray(): array_(), size_(0) {}
  Yarray(uint32_t sz): array_(), size_(sz) {}
  Yarray(const Yarray& other) {
	size_ = other.size();
  }
  inline uint32_t size() const { return size_; }
  inline uint32_t capacity() { return MAX_SIZE; }
  inline void reserve(uint32_t) {} // do nothing for now
  inline void push_back(T e) {
	array_[size_] = e; // assign first
	size_.fetch_add(1, std::memory_order_relaxed);
  }
  inline T* begin() { return array_; }
  inline T* end() { return array_ + size_; }

  T& operator[](uint32_t index) { return array_[index]; }

  void operator=(Yarray<T>& other) {
	const uint32_t sz = other.size();
	for (uint32_t i = 0; i < sz; i++)
	  array_[i] = other[i];
	size_.store(sz);
  }

 private:
  T array_[MAX_SIZE];
  std::atomic<uint32_t> size_;
};

} // namespace utils
} // namespace bess

#endif // BESS_UTILS_YARRAY_H_
