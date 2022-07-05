import enum

import password as password
from decouple import config
from flask import Flask, request
from flask_migrate import Migrate
from flask_restful import Api, Resource
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from marshmallow import Schema, fields, ValidationError, validate, validates
from password_strength import PasswordPolicy

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

# # функция за проверка на паролата, която проверява за грешки спрямо условията дефинирани отгоре
# def validate_password(value):
#     errors = policy.test(value)
#     if errors:
#         raise ValidationError(f"Not a valid password")
#
#
# # функция за валидира на името да е от 2 имена и да е по-голямо от 3 символа
# def validate_name(name):
#     try:
#         first_name, last_name = name.split()
#     except ValueError as ex:
#         # вдигаме ValidationError който идва от marshmallow и той сирилизира грешката и да я върне като отговор
#         raise ValidationError("First and Last name are mandatory!")
#     if len(first_name) < 3 or len(last_name) < 3:
#         raise ValidationError("Each name should contain at least 3 characters!")


class UserSignInSchema(Schema):
    email = fields.Email(required=True)

    # валидиране по 1вия начин с двете функции
    # password = fields.Str(required=True, validate=validate.And(validate_password, validate.Length(min=8, max=20)))
    # full_name = fields.Str(required=True, validate=validate.And(validate_name, validate.Length(min=3, max=255)))

    # валидиране по 2рия начин с validates decorator в класа
    password = fields.Str(required=True)
    full_name = fields.Str(required=True)

    """Валидиране на парола и име: 2ри начин"""
    # от marshmallow може да използваме validates който е декоратор на метод който да бъде в класа на схемата
    @validates("full_name")
    def validate_name(self, name):
        try:
            first_name, last_name = name.split()
        except ValueError:
            raise ValidationError("Full name should consist of first and last name at least")
        if len(first_name) < 3 or len(last_name) < 3:
            raise ValueError("Name should be at least 3 characters")


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


class ColorEnum(enum.Enum):
    pink = "pink"
    black = "black"
    white = "white"
    yellow = "yellow"


class SizeEnum(enum.Enum):
    xs = "xs"
    s = "s"
    m = "m"
    l = "l"
    xl = "xl"
    xxl = "xxl"


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


class UserSignIn(Resource):  # Ресурс за регистриране в системата.
    def post(self):
        # получаваме данните в json формат
        data = request.get_json()
        schema = UserSignInSchema()
        errors = schema.validate(data)
        if not errors:
            # създаваме си обект user (от клас User) който приема подадените данни от потребителя
            user = User(**data)
            db.session.add(user)  # вкарваме го в сесията
            db.session.commit()  # изпращаме всички промени към базата данни
        # ако има грешки фласк ги сирилизира от речник и ги връща като json обект
        return errors


api.add_resource(UserSignIn, "/register/")

if __name__ == "__main__":
    app.run(debug=True)
