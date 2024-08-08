from flask import Flask,render_template
app = Flask(__name__)
#need to make sure we create app first before all these files config. routes modesl etc
import config
#to import config.py file for os, dotenv for secrets and data for app
import routes
#for importing routes.py
import models
#for importing models
if __name__=='__main__':
    app.run(debug=True)

