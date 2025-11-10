#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

#include "threads/vaddr.h"       // For PHYS_BASE and is_user_vaddr()
#include "userprog/pagedir.h"  // For pagedir_get_page()
#include "threads/thread.h"      // For thread_current()
#include "userprog/process.h"  // For sys_exit()
#include "devices/shutdown.h"  // For shutdown_power_off()

static void sys_halt (void);
static void sys_exit (int status);
static int sys_exec (const char *cmd_line);
static int sys_wait (int pid);

static bool is_valid_user_ptr (const void *vaddr);
static int get_stack_arg (void *esp, int offset);
static bool is_valid_user_string (const char *str);

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

// This terminates Pintos
static void 
sys_halt (void) 
{
  shutdown_power_off(); // this effectively shuts down QEMU which closes Pintos
}

// this terminates the current user program
static void 
sys_exit (int status) 
{
  struct thread *cur = thread_current();
  cur->exit_code = status; // store exit code for process_exit()

  if (cur->pagedir != NULL) {
    printf("%s: exit(%d)\n", cur->name, status);
  }

  process_exit();   // clean up address space, close files, etc.
  thread_exit();    // now terminate the thread
}


// This executes a new process and
// returns the new process's ID (pid), or -1 if it fails.
static int
sys_exec (const char *cmd_line)
{
  /*
   * 1. Validate the string pointer and the string itself.
   * A bad string could crash the kernel.
   */
  if (!is_valid_user_string(cmd_line))
  {
    return -1;
  }
  
  /*
   * 2. Call the kernel's process_execute function.
   * This function creates a new thread and starts loading
   * the user program.
   */
  tid_t tid = process_execute (cmd_line);

  if (tid == TID_ERROR)
    return -1;
  
  return (int)tid;
}


/*
 * Waits for a child process (pid) to exit.
 * Returns the child's exit status.
 */
static int
sys_wait (int pid)
{
  /*
   * process_wait() is a kernel function that:
   * 1. Finds the child process with the given pid.
   * 2. Waits (blocks) until that child process calls exit().
   * 3. Returns the status that the child passed to exit().
   */
  return process_wait ((tid_t)pid);
}

/*
 * Checks if a user-provided virtual address is valid.
 * A valid pointer must:
 * 1. Not be NULL.
 * 2. Be in user space (below PHYS_BASE).
 * 3. Be mapped in the process's page table.
 */

static bool 
is_valid_user_ptr (const void *vaddr)
{
  if (vaddr == NULL) {
    return false;
  }
  
  // Check if it's a user address (not kernel)
  if (!is_user_vaddr(vaddr)) {
    return false;
  }
  
  // Check if it's mapped to a physical page
  struct thread *cur = thread_current ();
  if (pagedir_get_page(cur->pagedir, vaddr) == NULL) {
    return false;
  }
  
  return true;
}

/*
 * Reads a 4-byte value (like an int or a pointer) from the user's
 * stack at the given 'esp' + 'offset'.
 * Checks for validity before reading.
 * If invalid, exits the process.
 */
static int
get_stack_arg (void *esp, int offset)
{
  void *ptr = esp + (offset * 4); // 4 bytes per arg
  
  /*
   * We must check all 4 bytes of the argument.
   * For example, an 'int' could be split across
   * a page boundary (e.g., 3 bytes on one page, 
   * 1 byte on an unmapped page).
   */
  if (!is_valid_user_ptr(ptr) || 
      !is_valid_user_ptr(ptr + 3)) // Check the last byte
    {
      sys_exit (-1); // Invalid pointer, terminate
    }
  
  return *(int *)ptr; // Safe to read
}

/*
 * Helper function to validate a user-provided string.
 * Reads memory byte-by-byte until a null terminator
 * or an invalid address is found.
 */
static bool
is_valid_user_string (const char *str)
{
  if (!is_valid_user_ptr(str))
    return false;
  
  /* Check one byte at a time until we hit the null terminator */
  char *p = (char *)str;
  while (true)
    {
      if (!is_valid_user_ptr(p))
        return false; // Pointer is invalid

      if (*p == '\0')
        return true; // Found the end, string is valid
      
      p++; // Move to the next character
    }
}

static void 
syscall_handler (struct intr_frame *f) 
{
  void *user_esp = f->esp; 

  /*
  * ==== SECURITY CHECK 1 ====
  * First, check if the stack pointer *itself* is valid.
  * We need to read the system call number from it.
  */
  if (!is_valid_user_ptr(user_esp))
  {
    sys_exit (-1);
  }

  /*
  * Now it's safe to read the system call number.
  * We use our helper to do it safely.
  */
  int syscall_num = get_stack_arg(user_esp, 0);
  //int syscall_num = *(int *)f->esp;

  switch (syscall_num) {
    case SYS_HALT:
      sys_halt();
      break;
    case SYS_EXIT:
      int status = get_stack_arg(user_esp, 1);
      sys_exit(status);
      break;
    case SYS_EXEC:
      const char *cmd_line = (const char *)get_stack_arg(user_esp, 1);
      f->eax = sys_exec (cmd_line);
      break;
    case SYS_WAIT:
      int pid = get_stack_arg(user_esp, 1);
      f->eax = sys_wait (pid);
      break;
    case SYS_CREATE:
      printf ("System call %d not implemented yet.\n", syscall_num);
      sys_exit (-1);
      break;
    case SYS_REMOVE:
      printf ("System call %d not implemented yet.\n", syscall_num);
      sys_exit (-1);
      break;
    case SYS_OPEN:
      printf ("System call %d not implemented yet.\n", syscall_num);
      sys_exit (-1);
      break;
    case SYS_FILESIZE:
      printf ("System call %d not implemented yet.\n", syscall_num);
      sys_exit (-1);
      break;
    case SYS_READ:
      printf ("System call %d not implemented yet.\n", syscall_num);
      sys_exit (-1);
      break;
    case SYS_WRITE:
      printf ("System call %d not implemented yet.\n", syscall_num);
      sys_exit (-1);
      break;
    case SYS_SEEK:
      printf ("System call %d not implemented yet.\n", syscall_num);
      sys_exit (-1);
      break;
    case SYS_TELL:
      printf ("System call %d not implemented yet.\n", syscall_num);
      sys_exit (-1);
      break;
    case SYS_CLOSE:
      printf ("System call %d not implemented yet.\n", syscall_num);
      sys_exit (-1);
      break;
    default:
      printf("Unknown system call: %d\n", syscall_num);
      thread_exit();
  }
}
