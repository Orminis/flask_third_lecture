import enum
from marshmallow_enum import EnumField
from functools import wraps
from decouple import config
from flask import Flask, request
from flask_migrate import Migrate
from flask_restful import Api, Resource, abort
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from marshmallow import Schema, fields, ValidationError, validate, validates
from password_strength import PasswordPolicy
from werkzeug.security import generate_password_hash
import re

app = Flask(__name__)

db_user = config('DB_USER')
db_password = config("DB_PASSWORD")
db_host = config("DB_HOST")
db_name = config("DB_NAME")

app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://{db_user}:{db_password}@localhost:{db_host}/{db_name}'

db = SQLAlchemy(app)
api = Api(app)
migrate = Migrate(app, db)

# Определяне на условия за паролите чрез password_strength
policy = PasswordPolicy.from_names(
    uppercase=1,  # need min. 1 uppercase letters
    numbers=1,  # need min. 1 digits
    special=1,  # need min. 1 special characters
    nonletters=1,  # need min. 1 non-letter characters (digits, specials, anything)
)


# троен декоратор за валидиране на различни схеми
# schema_name = схемата която подаваме за валидиране
def validate_schema(schema_name):
    # взема функция
    def decorator(f):
        # wraps е от functools. използва се за да може да се вика името и документацията на функцията (f)
        @wraps(f)
        # взима args и kwargs на функцията
        def decorated_function(*args, **kwargs):
            schema = schema_name()
            errors = schema.validate(request.get_json())
            if errors:
                # Забранява продължението на функцията и подава грешка HTTP 400
                abort(400, errors=errors)
            return f(*args, **kwargs)

        return decorated_function

    return decorator


class ColorEnum(enum.Enum):
    pink = "pink"
    black = "black"
    white = "white"
    yellow = "yellow"
    red = 'red'
    blue = "blue"


class SizeEnum(enum.Enum):
    xs = "xs"
    s = "s"
    m = "m"
    l = "l"
    xl = "xl"
    xxl = "xxl"

# Schema която да опише всичко във обект Clothes
class SingleClothSchema(Schema):
    id = fields.Integer()
    name = fields.Str()
    # color/size не са стринг а enumerators и за да ги опишем в схемата като enumerators
    # използваме EnumField от marshmallow_enum.
    color = EnumField(ColorEnum, by_value=True)
    size = EnumField(SizeEnum, by_value=True)
    create_on = fields.DateTime()
    updated_on = fields.DateTime()


class UserOutSchema(Schema):
    id = fields.Integer()
    full_name = fields.Str()
    # изразяваме че
    # list от нестнати обекти от схемата SingleClothSchema
    clothes = fields.List(fields.Nested(SingleClothSchema), many=True)


class UserSignInSchema(Schema):
    full_name = fields.Str(required=True)
    password = fields.Str(required=True)
    email = fields.Email(required=True)

    # от marshmallow може да използваме validates който е декоратор на метод който да бъде в класа на схемата
    @validates("full_name")
    def validate_name(self, name):
        try:
            first_name, last_name = name.split()
        except ValueError:
            raise ValidationError("Full name should consist of first and last name at least")
        if len(first_name) < 3 or len(last_name) < 3:
            raise ValidationError("Name should be at least 3 characters")

    @validates("password")
    def validate_password(self, password):
        errors = policy.test(password)
        if errors:
            raise ValidationError(f"Password is not ok")

    @validates("email")
    def validate_email(self, email):
        email = email
        if re.match(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)", email):
            return "Email is valid"
        else:
            raise ValidationError("Email is not valid")

# junction table for connection between tables user and clothes
users_clothes = db.Table(
    # name of table
    "users_clothes",
    # metadata си идва от db.Model и просто трябва да се подаде
    db.Model.metadata,
    db.Column("user_id", db.Integer, db.ForeignKey("user.id")),
    db.Column("clothes_id", db.Integer, db.ForeignKey("clothes.id")),
)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(255), nullable=False)
    phone = db.Column(db.Text)
    # server_default - директно се създава с часа в който се създава
    create_on = db.Column(db.DateTime, server_default=func.now())
    # onupdate - записва последната редакция на този записва /  func.now() - от SQLAlchemy
    updated_on = db.Column(db.DateTime, onupdate=func.now())
    # relationship не променя базата а прави нова заявка да извлече информация за всички дрехи като дрехи обект
    # от junction table-a users_clothes
    clothes = db.relationship("Clothes", secondary="users_clothes")


class Clothes(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    color = db.Column(
        db.Enum(ColorEnum),
        default=ColorEnum.white,
        nullable=False
    )
    size = db.Column(
        db.Enum(SizeEnum),
        default=SizeEnum.s,
        nullable=False
    )
    photo = db.Column(db.String(255), nullable=False)
    create_on = db.Column(db.DateTime, server_default=func.now())
    updated_on = db.Column(db.DateTime, onupdate=func.now())


class UserSignUp(Resource):
    """Преди изпълнението на post заявката искаме да се изпълни валидирането на данните чрез декоратора validate_schema
    на който декоратор подаваме схемата UserSignInSchema по която схема искаме да се проверят данните.
    """

    @validate_schema(UserSignInSchema)
    def post(self):
        data = request.get_json()
        # hashing password with werkzeug.security
        data['password'] = generate_password_hash(data['password'], method='sha256')
        user = User(**data)
        db.session.add(user)
        db.session.commit()
        return data


class UserResource(Resource):
    def get(self, pk):
        user = User.query.filter_by(id=pk).first()
        # първо вдигаме обект от UserOutSchema и тогава го dump-ваме
        # dump = прави обекта от пайтън обект в json
        return UserOutSchema().dump(user)


api.add_resource(UserSignUp, "/register/")
api.add_resource(UserResource, "/users/<int:pk>/")

if __name__ == "__main__":
    app.run(debug=True)
