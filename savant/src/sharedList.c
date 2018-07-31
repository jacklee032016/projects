/*
* $Id: sharedList.c 908 2009-05-14 12:20:56Z lizj $
*/
#define	DLL_LIBRARY_EXPORT

#include "myDllDefs.h"

#define	shared_free		free
#define	shared_malloc	malloc

int DLL_DECLARE shared_list_init (shared_list_t * li)
{
	li->nb_elt = 0;
	return 0;/* ok */
}

int DLL_DECLARE shared_list_eol (const shared_list_t * li, int i)
{
	if(li==NULL)
		return -1;
	if (i < li->nb_elt)
		return 0;			/* not end of list */
	return 1;			/* end of list */
}


/* index starts from 0 */
void DLL_DECLARE *shared_list_get (const shared_list_t * li, int pos)
{
	__node_t *ntmp;
	int i = 0;

	if (pos < 0 || pos >= li->nb_elt)/* element does not exist */
		return 0;

	ntmp = li->node;/* exist because nb_elt>0 */
	while (pos > i)
	{
		i++;
		ntmp = (__node_t *) ntmp->next;
	}
	return ntmp->element;
}


/* return -1 if failed */
int DLL_DECLARE shared_list_remove (shared_list_t *li, int pos)
{
	__node_t *ntmp;
	int i = 0;

	if (pos < 0 || pos >= li->nb_elt)/* element does not exist */
		return -1;

	ntmp = li->node;		/* exist because nb_elt>0 */

	if ((pos == 0))
	{				/* special case  */
		li->node = (__node_t *) ntmp->next;
		li->nb_elt--;
		shared_free (ntmp);
		return li->nb_elt;
	}

	while (pos > i + 1)
	{
		i++;
		ntmp = (__node_t *) ntmp->next;
	}

	/* insert new node */
	{
		__node_t *remnode;

		remnode = (__node_t *) ntmp->next;
		ntmp->next = ((__node_t *) ntmp->next)->next;
		shared_free (remnode);
		li->nb_elt--;
	}
	return li->nb_elt;
}

void DLL_DECLARE shared_list_special_free (shared_list_t * li, void *(*free_func) (void *))
{
	int pos = 0;
	void *element;

	if (li == NULL)
		return;
	while (!shared_list_eol (li, pos))
	{
		element = (void *) shared_list_get (li, pos);
		shared_list_remove (li, pos);
		free_func (element);
	}
	shared_free (li);
}

void DLL_DECLARE shared_list_ofchar_free (shared_list_t * li)
{
	int pos = 0;
	char *chain;

	if (li == NULL)
		return;
	while (!shared_list_eol (li, pos))
	{
		chain = (char *) shared_list_get (li, pos);
		shared_list_remove (li, pos);
		shared_free (chain);
	}
	shared_free (li);
}

int DLL_DECLARE shared_list_size (const shared_list_t * li)
{
	if (li != NULL)
		return li->nb_elt;
	else
		return -1;
}

/* index starts from 0; */
int DLL_DECLARE shared_list_add (shared_list_t * li, void *el, int pos)
{
	__node_t *ntmp;
	int i = 0;

	if (pos == -1 || pos >= li->nb_elt)
	{				/* insert at the end  */
		pos = li->nb_elt;
	}

	if (li->nb_elt == 0)
	{
		li->node = (__node_t *) shared_malloc (sizeof (__node_t));
		li->node->element = el;
		li->nb_elt++;
		return li->nb_elt;
	}

	ntmp = li->node;		/* exist because nb_elt>0  */

	if (pos == 0)
	{
		li->node = (__node_t *) shared_malloc (sizeof (__node_t));
		li->node->element = el;
		li->node->next = ntmp;
		li->nb_elt++;
		return li->nb_elt;
	}
	/* pos = 0 insert before first elt  */

	while (pos > i + 1)
	{
		i++;
		/* when pos>i next node exist  */
		ntmp = (__node_t *) ntmp->next;
	}

	/* if pos==nb_elt next node does not exist  */
	if (pos == li->nb_elt)
	{
		ntmp->next = (__node_t *) shared_malloc (sizeof (__node_t));
		ntmp = (__node_t *) ntmp->next;
		ntmp->element = el;
		li->nb_elt++;
		return li->nb_elt;
	}

	/* here pos==i so next node is where we want to insert new node */
	{
		__node_t *nextnode = (__node_t *) ntmp->next;

		ntmp->next = (__node_t *) shared_malloc (sizeof (__node_t));
		ntmp = (__node_t *) ntmp->next;
		ntmp->element = el;
		ntmp->next = nextnode;
		li->nb_elt++;
	}
	return li->nb_elt;
}

