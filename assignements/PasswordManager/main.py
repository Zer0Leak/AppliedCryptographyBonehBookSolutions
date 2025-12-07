import test_password_manager


def __test_functionality() -> None:
    tests = test_password_manager.TestFunctionality()
    tests.test_init_without_error()
    tests.test_set_and_retrieve_password()
    tests.test_set_and_retrieve_multiple_passwords()
    tests.test_get_returns_none_for_non_existent_password()
    tests.test_can_remove_password()
    tests.test_remove_returns_false_if_no_password_for_name()
    tests.test_dump_and_restore_database()
    tests.test_fails_to_restore_database_with_incorrect_checksum()
    tests.test_fails_to_restore_database_with_incorrect_password()


def __main() -> None:
    __test_functionality()


if __name__ == "__main__":
    __main()
