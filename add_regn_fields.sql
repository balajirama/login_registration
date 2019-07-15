USE login_users;

INSERT INTO registration_form (name, label, type, placeholder) VALUES ('firstname', "First name", "text", "Jane");
INSERT INTO registration_form (name, label, type, placeholder) VALUES ('lastname', "Last name", "text", "Doe");
INSERT INTO registration_form (name, label, type, placeholder, small_text) VALUES ('email', "Email", "email", "me@example.com", "We'll never share your email with anyone else.");
INSERT INTO registration_form (name, label, type, placeholder) VALUES ('password', "Password", "password", "");
INSERT INTO registration_form (name, label, type, placeholder) VALUES ('confirm', "Confirm password", "password", "");
INSERT INTO registration_form (name, label, type, placeholder) VALUES ('dob', "Date of birth", "date", "");

INSERT INTO editprofile_form (name, label, type) VALUES ('firstname', "First name", "text");
INSERT INTO editprofile_form (name, label, type) VALUES ('lastname', "Last name", "text");
INSERT INTO editprofile_form (name, label, type, small_text) VALUES ('email', "Email", "email", "Your login will change if you change this.");
INSERT INTO editprofile_form (name, label, type) VALUES ('dob', "Date of birth", "date");

INSERT INTO editpassword_form (name, label) VALUES ("currentpassword", "Current password");
INSERT INTO editpassword_form (name, label) VALUES ("newpassword", "New password");
INSERT INTO editpassword_form (name, label) VALUES ("confirm", "Confirm password");

INSERT INTO languages (name) VALUES ("Python");
INSERT INTO languages (name) VALUES ("Javascript");
INSERT INTO languages (name) VALUES ("Java");
INSERT INTO languages (name) VALUES ("C++");
INSERT INTO languages (name) VALUES ("Perl");