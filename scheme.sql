CREATE TABLE country_code(
	CODE3 VARCHAR(3),
	CODE2 VARCHAR(2) NOT null,
	country VARCHAR(20) NOT null,
	CONSTRAINT country_code_pk PRIMARY KEY(CODE3)
);

CREATE TABLE member_type(
	code INT CHECK(CODE IN (1, 2, 3)),
	TYPE CHAR(20),
	CONSTRAINT member_typ_pk PRIMARY KEY(CODE)
);

CREATE TABLE member (
	id varchar(20),
	password varchar(20) not null,
	first_name_en varchar(20) not null,
	last_name_en varchar(20),
	first_name_ko varchar(20) not null,
	last_name_ko varchar(20),
	country_code varchar(3),
	institute varchar(20),
	type_code INTEGER,
	constraint member_pk primary key(id),
	constraint country_code_fk foreign key (country_code) references country_code(code3),
	CONSTRAINT member_type_fk FOREIGN KEY (type_code) REFERENCES member_type(CODE)
);

CREATE TABLE member_dev_as (
	id varchar(20),
	password varchar(20) not null,
	first_name_en varchar(20) not null,
	last_name_en varchar(20),
	first_name_ko varchar(20) not null,
	last_name_ko varchar(20),
	country_code varchar(3),
	institute varchar(20),
	type_code INTEGER,
	constraint member_dev_as_pk primary key(id),
	constraint member_dev_as_country_code_fk foreign key (country_code) references country_code(code3),
	CONSTRAINT member_dev_as_type_fk FOREIGN KEY (type_code) REFERENCES member_type(CODE)
);