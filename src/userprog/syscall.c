#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "filesys/filesys.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/* Check if a user virtual address is valid */
static bool
is_valid_user_addr (const void *uaddr)
{
  return uaddr != NULL && is_user_vaddr (uaddr) && 
         pagedir_get_page (thread_current ()->pagedir, uaddr) != NULL;
}

/* Safely get a 32-bit value from user memory */
static int
get_user_int (const void *uaddr)
{
  if (!is_valid_user_addr (uaddr))
    thread_exit ();
  return *(int *)uaddr;
}

/* Check if a buffer is valid */
static bool
is_valid_buffer (const void *buffer, unsigned size)
{
  unsigned i;
  char *buf;
  
  if (buffer == NULL || !is_user_vaddr (buffer))
    return false;
    
  /* Check if the entire buffer is in user space and mapped */
  buf = (char *)buffer;
  for (i = 0; i < size; i++)
    {
      if (!is_valid_user_addr (buf + i))
        return false;
    }
  return true;
}

static void 
syscall_handler(struct intr_frame *f) {
  /* Check if esp is valid */
  if (!is_valid_user_addr (f->esp))
    thread_exit ();
    
  int syscall_num = get_user_int (f->esp);

  switch (syscall_num) {
    case SYS_HALT:
      shutdown_power_off();
      break;
      
    case SYS_EXIT:
      {
        int status = get_user_int ((int *)f->esp + 1);
        
        struct thread *cur = thread_current();
        char name_copy[16];
        strlcpy(name_copy, cur->name, sizeof(name_copy));
        char *save_ptr;
        char *prog_name = strtok_r(name_copy, " ", &save_ptr);

        printf("%s: exit(%d)\n", prog_name, status);
        thread_exit();
        break;
      }
    case SYS_READ:
      {
        int i;
        int fd = -1;
        void *buffer = NULL;
        unsigned size = 0;

        /* esp 기준으로 최대 8칸까지 탐색 */
        for (i = 0; i < 8; i++) {
          void *arg1 = (int *)f->esp + i + 1;
          void *arg2 = (int *)f->esp + i + 2;
          void *arg3 = (int *)f->esp + i + 3;

          if (is_valid_user_addr(arg1) &&
              is_valid_user_addr(arg2) &&
              is_valid_user_addr(arg3)) {

            fd = get_user_int(arg1);
            buffer = (void *)get_user_int(arg2);
            size = get_user_int(arg3);

            if (fd == 0 && size > 0 && size < 1000 &&
                is_user_vaddr(buffer) && is_valid_buffer(buffer, size)) {

              unsigned i;
              uint8_t *buf = (uint8_t *) buffer;
              for (i = 0; i < size; i++) {
                buf[i] = input_getc(); // 키보드에서 1바이트 입력
              }

              f->eax = size;
              return;
            }
          }
        }

        f->eax = 0; // 실패 fallback
        break;
      }
    case SYS_WRITE:
      {
        int i;
        int fd = -1;
        void *buffer = NULL;
        unsigned size = 0;

        /* esp 기준으로 최대 8칸까지 시도 */
        for (i = 0; i < 8; i++) {
          void *arg1 = (int *)f->esp + i + 1;
          void *arg2 = (int *)f->esp + i + 2;
          void *arg3 = (int *)f->esp + i + 3;

          if (is_valid_user_addr(arg1) &&
              is_valid_user_addr(arg2) &&
              is_valid_user_addr(arg3)) {
            
            fd = get_user_int(arg1);
            buffer = (void *)get_user_int(arg2);
            size = get_user_int(arg3);

            if (fd == 1 &&
                size > 0 && size < 1000 &&
                is_user_vaddr(buffer) &&
                is_valid_buffer(buffer, size)) {
              putbuf((char *)buffer, size);
              f->eax = size;
              return;
            }
          }
        }

        /* 실패 fallback */
        f->eax = 0;
        break;
      }

    case SYS_CREATE:
      {
        int i;
        const char *file = NULL;
        unsigned initial_size = 0;

        for (i = 0; i < 8; i++) {
          void **arg1 = (void **)f->esp + i + 1;
          void *arg2 = (void *)((int *)f->esp + i + 2);

          if (is_valid_user_addr(arg1) && is_valid_user_addr(arg2)) {
            file = *(const char **)arg1;
            initial_size = get_user_int(arg2);

            if (is_valid_user_addr(file) && is_valid_buffer(file, 1)) {
              f->eax = filesys_create(file, initial_size);
              return;
            }
          }
        }

        f->eax = false;
        break;
      }
    case SYS_OPEN:
      {
        int i;
        const char *file = NULL;

        for (i = 0; i < 8; i++) {
          void **arg1 = (void **)f->esp + i + 1;

          if (is_valid_user_addr(arg1)) {
            file = *(const char **)arg1;

            if (is_valid_user_addr(file) && is_valid_buffer(file, 1)) {
              struct file *f_ptr = filesys_open(file);
              if (f_ptr == NULL) {
                f->eax = -1;
              } else {
                // 아주 간단히: 현재 쓰레드에 열린 파일 1개만 저장
                thread_current()->file = f_ptr;
                f->eax = 2;  // fd 2번으로 가정
              }
              return;
            }
          }
        }

        f->eax = -1;
        break;
      }
    case SYS_CLOSE:
      {
        int i;
        int fd = -1;

        for (i = 0; i < 8; i++) {
          void *arg1 = (int *)f->esp + i + 1;

          if (is_valid_user_addr(arg1)) {
            fd = get_user_int(arg1);

            if (fd == 2) {
              struct thread *cur = thread_current();
              if (cur->file != NULL) {
                file_close(cur->file);
                cur->file = NULL;
              }
              return;
            }
          }
        }

        break;
      }
    default:
      thread_exit();
  }
}
