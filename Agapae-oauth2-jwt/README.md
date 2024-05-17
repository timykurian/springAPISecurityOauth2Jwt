OAuth2 + JWT using Spring Boot 2 / Spring Security 5
---
Start the applications 
# OAuth2ServerJwtApplication
# ResourceServerJwtApplication

Test resource access 

If we access below GET api in browser ,we get below error 
http://localhost:9100/device/getDevice
 
Error Msg

```xml
<oauth>
<error_description>Full authentication is required to access this resource</error_description>
<error>unauthorized</error>
</oauth> 
``` 
Access the resource by passing the below credentials : 
 
 curl --location 'localhost:9100/device/getDevice' \
 --header 'clientId: secret' \
 --header 'grant_type: password' \
 --header 'username: user' \
 --header 'password: pass' \
 --header 'Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MTUyMjAwNzMsInVzZXJfbmFtZSI6InVzZXIiLCJhdXRob3JpdGllcyI6WyJST0xFX1VTRVIiXSwianRpIjoiMDc1ZTgzOTgtNmZiMi00MTBhLWEzMDktN2Y2ZTQ0MTM0OTM2IiwiY2xpZW50X2lkIjoiY2xpZW50SWQiLCJzY29wZSI6WyJyZWFkIiwid3JpdGUiXX0.RI5Vc2p6v9vH8ZGoEl5rn5Vur62t1RNdLvw327g7pJHggGO2tVmqcgvGSXUmcoV9gOjucpI_k11xIrucXwgbZdKkTeER7YRlwvhGY9whFWMapSowfh3q1ZqJe3xJXhUjO8v5FEhSmy7Wl8cw29rKBlD-6SPI7hCq8zwj6ZfmgwYwkzs-WaqWt3LKLU0-9YWVeMRAngmejFjW0AbBnI7t-3FMvkLzUyLLwywCDIlfYcEgqRb9ryJAHytRhB5Wk1gnuAWxf1m75MmOgw15rWpbG5hD4419zhwZ_31KuIx-A1qbvFDeGnwJ2kDAwd6Y1-dlLGeYxGA_ybbrWtxCbdd5dQ'
