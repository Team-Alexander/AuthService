package io.github.uptalent.auth.repository;

import io.github.uptalent.auth.model.hash.AccountVerify;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface AccountVerifyRepository extends CrudRepository<AccountVerify, String> {
}
