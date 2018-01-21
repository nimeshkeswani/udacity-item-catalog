This is an Item Catalog application. It uses Google's OAuth 2.0 for authentication and authorization.

All users can view Categories and Items, Only registered & authenticated users can create, update and delete items.

Also, only the creators themselves can edit and delete their own items.

The application also provides API endpoints for accessing and modifying the data. These endpoints also use Google's OAuth2.0 for authentication and authorization.

Steps to run this application:

1. Clone this Repository on your local computer
2. Go to the project directory
3. Run the statement "python models.py". This will setup the database for the application and create the database file in the folder.
4. Run the statement "python application.py". This will start the application.
5. You can then access the application at http://localhost:5000.