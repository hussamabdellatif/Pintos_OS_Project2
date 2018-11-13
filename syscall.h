#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);
int filesize(int fd);
unsigned tell (int fd);
int wait(int pid);
void seek(int fd, unsigned position);
int write(int fd, const void *buffer, unsigned size);
void exit(int status);

void halt(void);
int exec(const char* cmd_line);
void exit(int status);
int create(const char* file, unsigned initial_size);
void close(int fd);
int open(const char *filee);
int read(int, void*, unsigned);
#endif /* userprog/syscall.h */
