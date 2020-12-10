# Building: 
```
make
```

# Cleaning:
``` 
make clean
```

# How to Run: 
You will have to first compile decoder, encoder and filters, then you can run the following command:
``` 
sudo ./scheduler [incoming port]
```

# Where is the outgoing port for viewer?
The default port is used, which is 41234; depending on the jobs sent to the scheduler for each run, the outgoing viewer port will be the default port number plus 1. (e.g. when the second video request comes in, the viewer port is 41235)
Also, note that since multiple requests feature is not fully tested, I have manually set the scheduler to only accept a single request and shut itself down when finished. You can change this by going to line 360 and change the variable num_of_times_scheduler_run.

