package com.auth.service.repository;

import com.auth.service.models.ERole;
import com.auth.service.models.Role;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Optional;
public interface RoleRepository extends MongoRepository<Role, String> {
    Optional<Role> findByName(ERole name);
}