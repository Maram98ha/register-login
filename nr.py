import re
from fastapi import FastAPI, HTTPException
import sqlite3
import bcrypt

app = FastAPI()
conn = sqlite3.connect('user.db') 
cursor = conn.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS users
             (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT)''')
conn.commit()
#-----------------------------store user and pass----------------------------------------------------
def store_data(username, password):
    hash_pass = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hash_pass))
    conn.commit()
    return "User registered successfully!"

#----------------------------------------------------------------------------------------------------
def verify_data(username, password):
    cursor.execute("SELECT password FROM users WHERE username=?", (username,))
    hashed_password = cursor.fetchone()
    if hashed_password:
        return bcrypt.checkpw(password.encode('utf-8'), hashed_password[0])
    return False
#----------------------------------------------------------------------------------------------------
def check_username(username):
    cursor.execute("SELECT COUNT(*) FROM users WHERE username=?", (username,))
    count = cursor.fetchone()[0]
    return count>0
#-----------------------------------------------------------------------------------------------------
def check_password(password):
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters long")
    if not re.search(r'[0-9]', password):
        raise HTTPException(status_code=400, detail="Your password must include at least one number ")
    if not re.search(r'[!@#$%^&*]', password):
       raise HTTPException(status_code=400, detail= "Your password must include at least one special character") 
#def check_password(password):
   # if len(password) < 8:
    #    return False
   # if not re.search(r'[0-9]', password):
   #     return False
  #  if not re.search(r'[!@#$%^&*]', password):
  #      return False
 #   return True  
#------------------------------------------------------------------------------------------------------------------
@app.post("/register/{username}/{password}")
async def register_user(username:str,password:str):
    is_password_valid = check_password(password=password)
    if check_username(username):
       raise HTTPException(status_code=400, detail="Username already exists")
    store_result=store_data(username,password)
    return {"message": store_result}

#@app.post("/register/{username}/{password}")
#async def register_user(username: str, password: str):
   # if not check_password(password):  # Validate password
   #     return False
  #  if check_username(username):
  #      return False
 #   return store_data(username, password)

#-------------------------------------------------------------------------------------------------------------
@app.post("/login/{username}/{password}")
async def login_user(username:str,password:str):
 if verify_data(username, password):
    return {"message": "Login successful!"}
 else:
        raise HTTPException(status_code=401, detail="Invalid username or password")
 
#@app.post("/login//{username}/{password}")
#async def login_user(username: str, password: str):
 #   return verify_data(username, password)