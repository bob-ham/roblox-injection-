# roblox-injection via hooking
by the way if your gonna go this route you should know that your gonna be limited to one thread
unless you send your code to the threadpool which i say you should otherwise itll be hell
trying to run your code in one thread

like for example in your dll itll be like 
""
  HMODULE hSelf = GetModuleHandleA(NULL);
  
  PTP_WORK work = CreateThreadpoolWork(InitWork, hSelf, NULL);
  
  if (work) {
  
      SubmitThreadpoolWork(work);
      
      CloseThreadpoolWork(work);
      
  }
  
""
  
