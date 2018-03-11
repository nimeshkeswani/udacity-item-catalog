This is an Item Catalog application. It uses Google's OAuth 2.0 for authentication and authorization.

All users can view Categories and Items, Only registered & authenticated users can create, update and delete items.

Also, only the creators themselves can edit and delete their own items.

The application also provides API endpoints for accessing and modifying the data. These endpoints also use Google's OAuth2.0 for authentication and authorization.

Steps to run this application:

1. Clone this Repository on your local computer.
2. Make sure psql is installed.
3. Create a user called 'catalog' in psql. - sudo -u postgres createuser catalog
4. Set a password for the user 'catalog'. - 1. sudo -u postgres psql 2. alter user catalog with encrypted password 'catalog';
5. Create a database called 'catalog' in psql. - sudo -u postgres createdb catalog
6. Grant user 'catalog' full access to 'catalog' database in psql. - 1. sudo -u postgres psql 2. grant all privileges on database catalog to catalog;
7. Go to the project directory
8. Run the statement "python models.py". This will setup the database for the application and create the database file in the folder.
9. Run the statement "python application.py". This will start the application.
10. You can then access the application at http://localhost:5000.
