
# Project Item Catalog
Source code for Item catalog

## Overview
* allows users to view items ordered in categories
* allows logged in users to add categories, items, modify existing items and delete them 

## files and folders
* **models.py** : contains the definition of the database.
* **server.py** : the code for the server to handle all the functionality of the site  .
* **static folder** : contain resources (images and css) for the server to run and used to save user and item pictures.
* **templates folder** : contains html templates used to render pages.

## Instructions
* first you need to run in your **console**
    ```
    pip install -r requirements.txt
    ```
* you can run the server by running **server.py** in **console** after you run the **models.py** to create the database
* view the catalog at [this link](http://localhost:5000)
* server contain following json end points :
	* [get all categories details](http://localhost:5000/categories/json)
	* [get all items details](http://localhost:5000/items/json)
	* [get a certain item details](http://localhost:5000/items/item_id/json)
	* [get the full catalog details](http://localhost:5000/catalog/json)

## Requirements
* install python on your machine.
* install **requirements.txt**
* any modern web browser of your choice will work just well.