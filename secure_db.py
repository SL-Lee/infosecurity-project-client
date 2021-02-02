import json

import requests
from flask import request

from classes.models import *


class SecureDB:
    @classmethod
    def set_api_url(cls, api_url):
        cls.api_url = api_url

    @classmethod
    def set_api_key(cls, api_key):
        cls.__api_key = api_key

    @classmethod
    def create(cls, model, object_):
        try:
            schema = eval(f"{model}Schema()")
            object_ = schema.dumps(object_)
        except (NameError, SyntaxError) as exception:
            raise Exception from exception

        response = requests.post(
            cls.api_url,
            data={
                "model": model,
                "object": object_,
                "ip": request.remote_addr,
                "url": request.path,
            },
            headers={"X-API-KEY": cls.__api_key},
        )
        print(response.text)
        response.raise_for_status()

        try:
            schema = eval(f"{model}Schema()")
            created_object = schema.load(response.json()["created_object"])
        except (NameError, SyntaxError) as exception:
            raise Exception from exception

        return created_object

    @classmethod
    def retrieve(cls, model, filter_):
        response = requests.get(
            cls.api_url,
            params={
                "model": model,
                "filter": filter_,
                "ip": request.remote_addr,
                "url": request.path,
            },
            headers={"X-API-KEY": cls.__api_key},
        )
        print(response.text)
        response.raise_for_status()

        try:
            schema = eval(f"{model}Schema(many=True)")
            query_results = schema.load(response.json()["query_results"])
        except (NameError, SyntaxError) as exception:
            raise Exception from exception

        return query_results

    @classmethod
    def update(cls, model, filter_, values):
        response = requests.patch(
            cls.api_url,
            data={
                "model": model,
                "filter": filter_,
                "values": json.dumps(values, default=str),
                "ip": request.remote_addr,
                "url": request.path,
            },
            headers={"X-API-KEY": cls.__api_key},
        )
        print(response.text)
        response.raise_for_status()

    @classmethod
    def delete(cls, model, filter_):
        response = requests.delete(
            cls.api_url,
            data={
                "model": model,
                "filter": filter_,
                "ip": request.remote_addr,
                "url": request.path,
            },
            headers={"X-API-KEY": cls.__api_key},
        )
        print(response.text)
        response.raise_for_status()
