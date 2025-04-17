from django.http import HttpResponse

def home(request):
    return HttpResponse("Welcome to the Customer Order API. Visit /graphql for the GraphQL interface.")