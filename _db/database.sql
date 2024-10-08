create schema goapp collate utf8mb4_general_ci;
use goapp;

CREATE TABLE tbl_user
(
    id         INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    created    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated    TIMESTAMP    DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
    email      VARCHAR(255) NOT NULL,
    password   VARCHAR(255) NOT NULL,
    fullName   VARCHAR(255) NOT NULL,
    phone      VARCHAR(20)  DEFAULT NULL,
    roleMask   SMALLINT     DEFAULT NULL,
    isVerified SMALLINT     DEFAULT NULL
);