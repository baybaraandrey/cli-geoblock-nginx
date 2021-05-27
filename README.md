# CLI geoblock Installation

* Clone repo. and create virtualenv
```bash
git clone https://gitlab.com/yaricklavrinovich/cligeoblock
cd cligeoblock
python3 -m venv .env
source .env/bin/activate
pip install -r requirements.txt
cp alembic.ini.example alembic.ini
cp config.ini.example config.ini
```


* In gblock.py change path to your environment python interpreter
```
#!/path_environment/.env/bin/python3
```
* In alembic.ini change this line 
```.env
sqlalchemy.url = sqlite:////path/name.db # CHANGE ME!
```
* In config.ini change this line
 ```.env
sqlite=sqlite:////path/name.db # CHANGE ME!
```
* Create database and tables
```.bash
alembic revision --autogenerate
alembic upgrade head

```
* And try 
```bash
./block.py
```

* Load country codes
```bash
./block.py load codes --path iso3166.csv
./block.py show codes
```

