# library_management_api

This is a very basic library management api server with auth using flask, sqlalchemy, jwt.

#####User operations:

Create User with username, password
Login with username, password
View user list
Promote user to admin using public_id (created automatically)
####Library Management Operation

Add Book with ISBN, Name, Author Name
Edit Book using ISBN
Delete Book using ISBN
View Book list
Search Books with partial book name (like search used for this operation)
####Only Admin can create/promote user, view user list, add/edit/delete book.
####General user can login, view book list and search for books.


####Login
logs in user with username and password.
jwt token is created with public_id, expiration time=1 hour, app secret key.
return: token

####Login_required
decorator to check if user is logged in
return: logged in user or proper error response.

####Create_user
creates user with username, password. public_key is auto-generated and is_admin is by default False.
current_user:
return: Result response

####User_list
current_user:
return:list of users(username, public_id and is_admin)

####Promote_users_to_admin
Promote user to admin
current_user:
public_id:
return: Result response


####Add_book
add new book with isbn, name, author name.
current_user:
return: result response


####Edit_book
 edit book info using isbn.
current_user:
isbn:
return: result response


####Delete_book
delete book using isbn
current_user:
isbn:
return: result response


####List_of_book
current_user:
return: list of books(isbn, name, author name)


####Search_book
search for book using partial string search
current_user:
return: list of books




