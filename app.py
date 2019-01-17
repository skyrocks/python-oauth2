from website.app import create_app


app = create_app({
    'SECRET_KEY': 'secret',
    'OAUTH2_REFRESH_TOKEN_GENERATOR': True,
    'SQLALCHEMY_TRACK_MODIFICATIONS': False,
    'SQLALCHEMY_DATABASE_URI': 'sqlite:///db.sqlite',
})


@app.cli.command()
def initdb():
    from website.models import db
    db.create_all()


# by shilei 2019-01-16 23:57 begin
# You can run flask in PyCharm
import os
os.environ["AUTHLIB_INSECURE_TRANSPORT"] = "1"
app.run()
# by shilei 2019-01-16 23:57 end