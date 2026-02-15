import os
import sqlite3

clave_aws = "AKIAIOSFODNN7EXAMPLE" #Deberia ir en variables de entorno

query = "SELECT * FROM usuarios WHERE nombre = " + usuario #Inyeccion SQL

eval("print('hola mundo')") #Ejecuta cadenas de texto como codigo arbitrario => inyeccion codigo malicioso

servidor_interno = "192.168.1.50" #IP hardcodeada