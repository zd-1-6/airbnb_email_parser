create a new folder, place the python program in it and one or mor email files .eml

to run the program locally (with Python already isntalled) do this:

py airbnb_eml_to_sql.py --input *.eml

this will parse as many .eml files you have in the directory and create an INSERT statement for each of them

or you can explicitly name one or more .eml

py airbnb_eml_to_sql.py --input one.eml two.eml