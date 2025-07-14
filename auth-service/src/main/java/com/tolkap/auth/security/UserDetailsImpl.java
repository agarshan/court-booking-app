package com.tolkap.auth.security;

import com.tolkap.auth.model.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

public class UserDetailsImpl implements UserDetails {

    private final User user;

    public UserDetailsImpl(User user) {
        this.user = user;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority("ROLE_" + user.getRole().name()));
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getEmail(); // or user.getUsername() depending on your login logic
    }

    @Override
    public boolean isAccountNonExpired() {
        return true; // or your own logic
    }

    @Override
    public boolean isAccountNonLocked() {
        return true; // or your own logic
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true; // or your own logic
    }

    @Override
    public boolean isEnabled() {
        return true; // or your own logic
    }
}
