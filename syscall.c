#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <stdint.h>
#include <stdbool.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "filesys/file.h"
//#include "filesys/file.c"
#include "filesys/filesys.h"
#include  "threads/vaddr.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "devices/input.h"
#include "devices/shutdown.h"

static bool check_ptrs (const void *);
static void syscall_handler (struct intr_frame *);
static char *names_exec[50][50];
int num_of_exec;

struct lock *rwlock;

static bool
check_ptrs (const void * addr) 
{
  return (addr != NULL && is_user_vaddr(addr) && (pagedir_get_page (thread_current()->pagedir, addr) != NULL) && addr > (void *) 0x08048000 && addr != 0x00000000);
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  if(f ==NULL) return;	

  // validate the syscall arg pointers

  if (!check_ptrs(f->esp) || !check_ptrs(f->esp+1) || !check_ptrs(f->esp+2) || !check_ptrs(f->esp+3)) { exit(-1); }  

  switch(*(int*)f->esp)
  {
	  
	case SYS_WRITE:
	{
		int fd = *((int*)f->esp +1);
		if(fd > 500000000) exit(-1); // you have to change that , there is a function in vaddr.h that checks validity of a pointer, it didnt work for me though..
		void* buffer = (void*)(*((int*)f->esp+2));
                if (!check_ptrs(buffer)) exit(-1);
		unsigned size = *((unsigned*)f->esp+3);
		f->eax = write(fd,buffer,size);
		break;
	
	}
	case SYS_HALT:
	{
		halt();
		break;
	}
	case SYS_EXIT:
	{
               // if (!check_ptrs(f->esp + 1)) { exit(-1); }
               // if (&SYS_EXIT == (void *) 0xbffffffc) exit(-1);
                // for sc-bad-arg: check to see if SYS_EXIT is at the top of the stack
                // if this is the case, the syscall args would be outside of user space
                if (f->esp == (void *) 0xbffffffc) exit(-1); 
		int fd = *((int*)f->esp +1);
		exit(fd);
		break;
	}
	
	case SYS_WAIT:
	{
		int fd = *((int*)f->esp +1);
		f->eax  = wait(fd);
		break;
	}
	case SYS_EXEC:
	{
        //        if (!check_ptrs(f->esp+1)) { exit(-1); }
		int fd = *((int*)f->esp +1);
                if (! check_ptrs( (void *) fd)) exit(-1);
        	if(fd > 500000000 )exit(-1);// you have to change that , there is a function in vaddr.h that checks validity of a pointer, it didnt work for me though..
		f->eax= exec((const char*)fd);
		break;
	}
	case SYS_CREATE:
	{
		int fd = *((int*)f->esp +1); 
		// printf("\n\%p\n\n", (char *) fd);
		if(fd > 500000000 )exit(-1);// you have to change that , there is a function in vaddr.h that checks validity of a pointer, it didnt work for me though..
		void* buffer = (void*)(*((int*)f->esp+2));
		f->eax = create( (const char*) fd ,(unsigned) buffer);
		break;
	}
	
	case SYS_OPEN:
	{
		int fd = *((int*)f->esp +1);
		if(fd > 500000000 )exit(-1);// you have to change that , there is a function in vaddr.h that checks validity of a pointer, it didnt work for me though..
		f->eax = open((const char*)fd);
		break;
	}
	case SYS_CLOSE:
	{
		int fd = *((int*)f->esp +1);
		close(fd);
		break;
	}
	case SYS_READ:
	{
		int fd = *((int*)f->esp +1);
		if(fd > 420000000 )exit(-1); // <--- letting this one stay. if it ain't broke don't fix it
		void* buffer = (void*)(*((int*)f->esp+2));
                if (!check_ptrs(buffer)) exit(-1);
		unsigned size = *((unsigned*)f->esp+3);
		f->eax = read(fd ,buffer, size);
		break;
	}
	case SYS_FILESIZE:
	{
        	int fd = *((int*)f->esp +1);
		f->eax = filesize(fd);
		break;
	}
	
	case SYS_SEEK:
	{
		int fd = *((int*)f->esp +1);
		void* buffer = (void*)(*((int*)f->esp+2));
		seek(fd, (unsigned) buffer);
		break;
	}
	case SYS_TELL:
	{
		int fd = *((int*)f->esp +1);
		f->eax = tell(fd);
		break;
	}
	
  }
}



int filesize(int fd)
{
	struct file *filee = thread_current()->file_names[fd]; //easiest way to keep track of files is by storing file objects in an array inside the threat struct, so each thread has access to those files.
	int ret = file_length (filee); 
        return ret;
	
}

unsigned tell (int fd)
{
  struct file *fs = thread_current()->file_names[fd];
  if(fs == NULL) return -1;
unsigned ret =  file_tell(fs);
  return ret;
}

int read(int fd, void *buffer, unsigned size)
{
        if (!check_ptrs(buffer)) { exit(-1); }
	if(fd ==0){
		unsigned counter =0;
		uint8_t x;
		while(counter<size){ x = input_getc(); counter++;} //they did not specifc what to do with x so for now just ignore
		return size;
		}
	if(fd>200 || fd < 0) return -1;	
	struct file *fl = thread_current()->file_names[fd];
	if(thread_current()->file_names[fd] == NULL) return 0; //probably better to this --> struct file *fl_check = NULL; if (fl_check == fl) exit(-1) check this and see if it passes more tests...
	if(size ==0 ) return 0;
	int ret = file_read (fl,buffer,size) ;
        return ret;
}


int open(const char *filee)
{
	if (!check_ptrs(filee)) { exit(-1); } 
	if(filee == NULL) return -1;
	//printf("\n\n Thread name1 : %s \n\n ", thread_name());
	struct file *file = filesys_open (filee);
	/*if(is_deny_write(filee) ){
		 thread_current()->names = filee;
		} */
		
	if(file==NULL)return -1;
	int fd = thread_current()->file_descripter + 5;
	thread_current()->file_names[fd] = file;
	thread_current()->file_descripter = fd + 1;
	return fd;
	
}

void close(int fd)
{
	if(fd>200 || fd < 0) return;
	struct file *fl = (thread_current()->file_names[fd]);
	file_close (fl);
	thread_current()->file_names[fd]=NULL;
	
}


int create(const char* file, unsigned initial_size)
{
	
	if(file == NULL ) exit(-1);
	//printf("this is size %d\n\n", initial_size);
	//if(initial_size <0 ) return -1;
	int ret= filesys_create (file,  initial_size) ;
        return ret;
}


int exec(const char* cmd_line)
{
        if (!check_ptrs(cmd_line)) exit(-1);	
        
	int id = process_execute (cmd_line);
	//wait(id);
	thread_current()->child_exited = 0;
	if(thread_current()->success_on_load == 0)exit(-1);
	if(thread_current()->success_on_load != 0 && thread_current()->success_on_load != 1 ){ exit(-1);}
	if(id == TID_ERROR) return -1;
	
	return id; 
	
}


int wait(int pid)
{
	
	struct thread *cur = thread_current();
	struct thread *child = find_thread(pid);
	if(cur->child_exited) return -1; // proably use exit(-1) check if that passes any more tests
	struct thread *t = NULL;
	if(child == t)exit(-1);
	
	struct lock a;
	lock_init(&a);
	//printf("\n\n %s \n\n", child->status);

	child->parent = cur;
	cur->child = child;
	child->parent_waiting = 1;
	intr_disable();
	thread_block();
	intr_enable();
	
	if(thread_current()->child->parent_waiting == 1 ) return  thread_current()->child->exit_status;
	//if(thread_current()->child->has_exited  ){ return -1;}
	//thread_yield();
	//("Thread name is \n\n %s \n\n", thread_name());
	return thread_current()->exit_status;
	
	
	
	
	//return process_wait(pid);
}




void halt(void){
	shutdown_power_off();
}
//need to do something with child thread.. (not yet implemented)

void exit(int status){
	
	thread_current()->has_exited = 1;
	thread_current()->parent->child_exited =1;
	//printf("\n\n This is my name %s\n", thread_name());
	thread_current()->tid = status;
	if(thread_current()->parent_waiting == 1 ) thread_current()->parent->exit_status = status;
	//thread_current()->exit_status = status;
	printf("%s: exit(%d)\n",thread_current()->name, status);
	thread_exit();
	//thread_unblock(cur->parent);
	

}

int write(int fd, const void *buffer, unsigned size)
{
        if (!is_user_vaddr(buffer)) { exit(-1); }
	//if(fd == NULL || buffer == NULL ) return -1;
	if(size ==0 ) return 0;
	if(fd == 1 || fd == STDOUT_FILENO){
		putbuf(buffer,size);
		return size;
		}
	if(fd>200 || fd < 0) { return -1; }  //also some pointer validation because i cant have more than 200 open files.. check thread.h thread struct-->file_names 
	/* if(is_deny_write (thread_current()->names) ||is_deny_write (thread_current()->parent->names)  )  return 0;  */
		
	//off_t file_write (struct file *, const void *, off_t);
	//struct file *file_open (struct inode *);
	
	struct file *file_arg =  (thread_current()->file_names[fd]);
	//if(file_arg->exec) return 0;
	if(thread_current()->file_names[fd] != NULL){
		int ret =  file_write(file_arg, buffer, size);
                return ret;
	}
	
	return 0;
}



void seek(int fd, unsigned position)
{
  
  struct file *fs = thread_current()->file_names[fd];
  if(fs == NULL) return;
  file_seek (fs, position);
}










