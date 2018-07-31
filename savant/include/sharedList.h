/*
* $Id: sharedList.h 908 2009-05-14 12:20:56Z lizj $
*/

#ifndef __SHARED_LIST_H__
#define __SHARED_LIST_H__


/**
 * This is a very simple implementation of a linked list.
 * There is not much to say about it... Except that it could be a lot improved. Sadly, it would be difficult
 * to improve it without breaking the compatibility with older version!
 */
#ifdef __cplusplus
extern "C"
{
#endif

//#pragma pack(1)

typedef struct __node __node_t;


struct __node
{
	void		*next;			/**< next __node_t containing element */
	void		*element;              /**< element in Current node */
};//__attribute__((packed)) ;

typedef struct shared_list shared_list_t;

struct shared_list
{
	int			nb_elt;         /**< Number of element in the list */
	__node_t		*node;     /**< Next node containing element  */
};//__attribute__((packed)) ;

//#pragma pack(pop)

#ifdef __cplusplus
}
#endif

#endif

