#include "utils/string.h"
#include "datastructures/bst.h"

#include "codes/node.h"
#include "codes/datatype.h"

#include "logger.h"

static char ret;
static char absolute(char value)
{
  if (value<0) return -value;
  else return value;
}

static char insertNodeFun(BinarySearchTree** root, Node* node)
{
  if (*root == NULL) { *root = node; return 0; }
  else {;}

  char ret_val;
  char compare = stringsCompare(node->key, ((Node*) (*root))->key);

  if (!compare) return -1;
  else {;}

  if(!ret)
  {
    ret = compare;
    if(compare<0) ret_val = insertNodeFun(&((Node*)(*root))->left, node);
    else if(compare>0) ret_val = insertNodeFun(&((Node*)(*root))->right, node);
    else {;}
  }
  else if(absolute(ret) <= absolute(compare))
  {
    ret = compare;
    if(compare<0) ret_val = insertNodeFun(&((Node*)(*root))->left, node);
    else if(compare>0) ret_val = insertNodeFun(&((Node*)(*root))->right, node);
    else {;}
  }
  else if(absolute(ret) > absolute(compare)) return -1;
  else {;}

  if(ret_val == -1)
  {
    if(compare<0)
    {
      node->left = ((Node*)(*root))->left;
      ((Node*)(*root))->left = node;
      return 0;
    }
    else if(compare>0)
    {
      node->right = ((Node*)(*root))->right;
      ((Node*)(*root))->right = node;
      return 0;
    }
    else {;}
  }
  else {;}
}

char insertNode(BinarySearchTree** root, Node* node)
{
  ret = 0;
  insertNodeFun(root, node);
}

BinarySearchTree* getNode(BinarySearchTree* root, char letter, short* index)
{
  if (root == NULL) return root;
  else {;}

  if(*((root->key)+(*index)) < letter)return getNode(root->right, letter, index);
  else if(*((root->key)+(*index)) > letter) return getNode(root->left, letter, index);
  else if(*((root->key)+(*index)) == letter) { *index+=1; return root; }
}

void freeTree(BinarySearchTree* root)
{
  if (root==NULL) return;
  else {;}

  freeTree(root->left);
  freeTree(root->right);

  if(root->type == VARIABLE_NODE)
  {
    UserVariable* variable = (UserVariable*) root->data;
    if(variable == NULL) {;}
    else
    {
      if(variable->datatype == PACKET_TYPE_CODE)
      {
        Packet* packet = (Packet *) variable->value;
        if(packet == NULL) goto skip;
        else {;}

        if(packet->packet_buff != NULL && packet->layer == EMPTY_CONTAINER)
        {
          #if LOGGING_ENABLED(LOG_MEMORY) > 0
          MEMORY_LOGGING_UTIL("F\0", (long int) 0, packet->packet_buff, "UserVariable->Packet->packet_buff");
          #endif
          free(packet->packet_buff);
          packet->packet_buff = NULL;
        }
        else {;}

//        #if LOGGING_ENABLED(LOG_MEMORY) > 0
 //         MEMORY_LOGGING_UTIL("F\0", sizeof(Packet), packet, "UserVariable->Packet");
  //      #endif
        //free(packet);
        //packet=NULL;
      }
      else {;}

      skip:

      // NEED TO BE FREED... BUT A POINTER POINTS TO INVALID MEM... THERE IS AN EXTRA OOB NODE
      //if(variable->identifier != NULL) { free(variable->identifier); variable->identifier = NULL; }
      //else {;}
      // NEED TO BE FREED... BUT A POINTER POINTS TO INVALID MEM... THERE IS AN EXTRA OOB NODE

      if(variable->value != NULL)
      {
        #if LOGGING_ENABLED(LOG_MEMORY) > 0
          MEMORY_LOGGING_UTIL("F\0", (long int) 0, variable->value, "UserVariable->value");
        #endif
        free(variable->value); variable->value == NULL;
      }
      else {;}

      #if LOGGING_ENABLED(LOG_MEMORY) > 0
        MEMORY_LOGGING_UTIL("F\0", (long int) 0, variable, "UserVariable");
      #endif
      free(variable);
      variable = NULL;
    }
  }
  else {;}

  #if LOGGING_ENABLED(LOG_MEMORY) > 0
    MEMORY_LOGGING_UTIL("F\0", sizeof(Node), root, "Node in BST");
  #endif
  free(root);
  root = NULL;
}


/*

======================================================================
|----------------- DEBUG FUNCTION USED BY THE AUTHOR ----------------|
|--------------------------------------------------------------------|
|-USE THESE OR DEFINE YOUR OWN FUNCTIONS TO DEBUG DURING DEVELOPMENT-|
======================================================================

void pre(BinarySearchTree* root)
{
  if (root==NULL) return;
  else {;}

  printf("<>\n");
  if(root->left != NULL) printf("<-L->\n");
  if(root->right != NULL) printf("<-R->\n");
  pre(root->left);
  pre(root->right);
}

 ===================================================================
 | DEPRECATED INSERT - LEFT WITHOUT REMOVING FOR FUTURE REFERENCES |
 ===================================================================

char insertNode(BinarySearchTree** root, Node* node, short index)
{
  if (*root == NULL) { *root = node; return 0; }
  else {;}

  if(*((((Node*) (*root))->key)+index) < *((node->key)+index)) return insertNode(&(((Node*) (*root))->right), node, index);
  else if(*((((Node*) (*root))->key)+index) > *((node->key)+index)) return insertNode( &(((Node*)(*root))->left), node, index);
  else if(*((((Node*) (*root))->key)+index) == *((node->key)+index))
  {
    if (!*((((Node*) (*root))->key)+index)) return ((Node*)(*root))->type;// Node Already Exists !
    else return insertNode(root, node, index+1);
  }
}

*/
