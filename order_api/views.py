from django.shortcuts import render
from django.http import HttpResponse

def home(request):
    return HttpResponse(
        'Welcome to the <a href="http://127.0.0.1:8000/graphql">Customer Order API</a>. Visit <code>/graphql</code> for the GraphQL interface.'
    )
