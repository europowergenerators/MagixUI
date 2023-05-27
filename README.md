# Magix UI

Launch processes onto the interactive desktop from LOCAL_SYSTEM. The code is a port of [code from this MSDN post](http://web.archive.org/web/20230526131140/https://learn.microsoft.com/en-us/previous-versions//aa379608%28v=vs.85%29).  
This is kind-of like PSExec and ServiceUI, with a difference that the process user can be different than SYSTEM and the process user can be different than the one with an active desktop session.