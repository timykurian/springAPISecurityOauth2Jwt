package com.agapae.sec.oauth.jwt.ds.web;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
@RequestMapping("/device")
public class UserController {

    @GetMapping("/getDevice")
    @PreAuthorize("hasRole('ROLE_USER')")
    //Only users with the role ROLE_USER are allowed to access this endpoint,
    // Otherwise, it denies access with an appropriate error message or status code.
    public ResponseEntity getDevice(final Principal principal) {
        return ResponseEntity.ok("{"
                +"  deviceName:NookColor"
                +", deviceModel:BNXRVB"
                +", deviceSN:52348356082459945034" +
                "\n\n   " +
                "Authorized with:"+principal.getName()+"}");
    }


    /**
     *
     *
     * @param principal
     * @return
     */
    @GetMapping
    @PreAuthorize("hasRole('ROLE_USER')")//Only users with the role ROLE_USER are allowed to access this endpoint.
    public ResponseEntity<Principal> get(final Principal principal) {
        return ResponseEntity.ok(principal);
    }


}
