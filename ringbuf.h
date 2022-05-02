#ifndef K2_SCHEDULER_RINGBUF_H
#define K2_SCHEDULER_RINGBUF_H

struct ringbuf {
	void *data;
	ssize_t capacity;

	void *head;
};

#define ringbuf_init(__rb__, __capacity__, __type__)                           \
	({                                                                     \
		(__rb__)->capacity = __capacity__;                             \
		(__rb__)->data = kzalloc((__capacity__) * sizeof(__type__),    \
					 GFP_KERNEL);                          \
		(__rb__)->head = (__rb__)->data;                               \
	})

#define ringbuf_inc_pointer(__rb__, __p__, __type__)                           \
	({                                                                     \
		if ((__p__) >= (__rb__)->data + ((__rb__)->capacity - 1) *     \
							sizeof(__type__)) {    \
			(__p__) = (__rb__)->data;                              \
		} else {                                                       \
			(__p__) += sizeof(__type__);                           \
		}                                                              \
	})

#define ringbuf_pushback(__rb__, __elem__, __old__, __type__)                  \
	({                                                                     \
		(__old__) = *(__type__ *)((__rb__)->head);                     \
		*(__type__ *)(__rb__)->head = __elem__;                        \
		ringbuf_inc_pointer(__rb__, (__rb__)->head, __type__);         \
	})

#define ringbuf_set_all(__rb__, __val__, __type__, __vp__)                     \
	({                                                                     \
		for ((__vp__) = (__rb__)->data;                                \
		     (__vp__) <                                                \
		     (__rb__)->data + (__rb__)->capacity * sizeof(__type__);   \
		     (__vp__) += sizeof(__type__)) {                           \
			*((__type__ *)(__vp__)) = __val__;                     \
		}                                                              \
	})

void ringbuf_free(struct ringbuf *rb)
{
	if (rb->data) {
		kfree(rb->data);
	}
}

#endif // K2_SCHEDULER_RINGBUF_H
