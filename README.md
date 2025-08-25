PintOS Project 
---
**Operating Systems Course Project (2025-1)**  
> All original content of PintOS is available at [Stanford CS140 PintOS](http://www.stanford.edu/class/cs140/projects/pintos)  
> Source code available through branch switching  


Overview
---
This project is based on **PintOS**, a simple operating system framework used for educational purposes.  
Throughout the semester, we gradually built and expanded core components of the OS, focusing on **thread management, system calls, virtual memory**, and **file systems**.


Project Breakdown
---

### Project 1 – **Threads & Scheduling**
- Implemented an **alarm clock** feature using timer interrupts.
- Added **priority-based scheduling**, including priority donation to prevent priority inversion.

### Project 2-1 – **User Programs (Part 1)**
- Implemented **argument passing** to user programs.
- Added essential **system calls**: `halt`, `exit`, `create`, `open`, `close`, `write`.

### Project 2-2 – **User Programs (Part 2)**
- Completed remaining **system calls**: `read`, `write`, `exec`, `wait`, `remove`, `filesize`, `seek`, `tell`.
- Implemented **process synchronization** for proper `wait` and `exec` behavior.
- Introduced protection to **deny writes to executable files**.

### Project 3 – **Virtual Memory**
- Designed and implemented a **supplementary page table (SPT)**.
- Added support for **stack growth** and **memory swapping**.
- Integrated **memory-mapped file (mmap)** support.

### Project 4 – **File System**
- Extended the file system to support **double-indirect block entries** for larger files.

---

## Contributors
- **KangJun Lee** | [suri7897@unist.ac.kr](mailto:suri7897@unist.ac.kr)  
- **Donguk Kim** | [freezing16@unist.ac.kr](mailto:freezing16@unist.ac.kr)
