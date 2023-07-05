# TLS Load Testing

Runs local radiusd load testing for TLS using docker compose.  
Requires Docker.  
### Usage:  
`bash run_test.sh (number of concurrent clients/servers running)`  
### Options:  
- `-n`: number of messages to send per client (default is 1000)
- `-l`: log level for home/proxy servers (default is 1, 1=`radiusd -f`, 2=`radiusd -fx`, 3=`radiusd -fxx`, other=no log files generated)
- `-o`: where to put log files after running (default is `./test/containers`)
- `-i`: name of generated docker image (only needed if you have generated your own docker image to run, rather than the one from the repository)
- `-d`: folder path to the Dockerfile to build
- `-r`: the Github branch to build from
- `-b`: force rebuilding the docker image, even if it already exists
 
### Output:  
- `client_*.log`: Output of radclient for each running client
- `home_server_*.log`: Output from radiusd of home servers
- `proxy_server.log`: Output from radiusd of proxy server

Additional output can be read by running `docker compose --scale client=n --scale home=n` after `run_test.sh` performs an initial setup, but this should not be necessary unless debugging the test itself.  

### Result:
The script will exit 0 if all clients succeed or 1 if any client fails, and will print a corresponding message for convenience.  