start the lab
the html page with api doc we get
bottom of the home page we got this curl command
replace /host with the domain url we got for the lab

curl -H "Accept: application/json" http://chall-132f7719.evt-246.glabs.ctf7.com/api/v1/healthcheck

then we got a json response with internal token that had the flag
