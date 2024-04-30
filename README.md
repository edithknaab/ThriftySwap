#Thrift Owl Swap Shop
Prerequisites: 

Python 3.8+ 
Pip 
A command-line interface 
Installation Steps: 

Clone the repository: 
git clone https://github.com/edithknaab/ThriftySwap 
Set up a virtual environment: 
python -m venv env source env/bin/activate (On Windows use `env\Scripts\activate` ) 
Install required packages: 
pip install -r requirements.txt  
Initialize the database: 
python manage.py migrate  
Run the application: 
python manage.py runserver (Access the application at http://localhost:8000/.) 
