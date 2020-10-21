#ifndef _UTIL_MQUEUE_H
#define _UTIL_MQUEUE_H

// Implementation taken from
// http://www.soa-world.de/echelon/uploaded_files/lockfreequeue.cpp
// http://www.soa-world.de/echelon/2011/02/a-simple-lock-free-queue-in-c.html
//
// Provides a lock free queue for single producer, single consumer applications
#include <string>

namespace mckeys {

// You can't put the implementation for template classes into a cpp file.
// Awesome sauce!
template <typename T>
class mqueue
{
 public:
  mqueue() {
    first = new Node(T());
    divider = first;
    last = first;
  }
  ~mqueue() {
    uint32_t deleted = 0;
    while(first != NULL)                                      // release the list
    {
      Node* tmp = first;
      first = tmp->next;
      deleted += 1;
      delete tmp;
    }
  }

  void produce(const T& t) {
    last->next = new Node(t);                               // add the new item
    asm volatile("" ::: "memory");                          // prevend compiler reordering
    // gcc atomic, cast to void to prevent "value computed is not used"
    (void)__sync_lock_test_and_set(&last, last->next);
    while(first != divider)                                 // trim unused nodes
    {
      Node* tmp = first;
      first = first->next;
      delete tmp;
    }
  }

  bool consume(T& result) {
    if(divider != last)                                     // if queue is nonempty
    {
      result = divider->next->value;                        // C: copy it back
      asm volatile("" ::: "memory");                        // prevent compiler reordering
      // gcc atomic, cast to void to prevent "value computed is not used"
      (void)__sync_lock_test_and_set(&divider, divider->next);
      return true;                                          // and report success
    }
    return false;                                           // else report empty
  }

  // TODO add count for use in shutdown

 private:
  struct Node
  {
    Node(T val) : value(val), next(NULL) { }
    T value;
    Node* next;
  };
  Node* first;                                            // for producer only
  Node* divider;                                          // shared
  Node* last;                                             // shared
};

} // end namespace

#endif
