# CS50 Finance Readme

- A web app created with Python and Flask as part of Harvard's CS50 course where users are able to 'buy' and 'sell' stocks and look up the pricing of stocks.
- Handles user requests and uses IEX API for real-time data retrieval.
- Incorporates user authentication and dynamic web page rendering using Jinja templating.

## Languages Used
- Python
- Flask
- Jinja
- SQL
- HTML

## Pages

### Register/Login:
- Page where users can register for an account and login through user authentication. Will notify the user if their credentials are not found.

### Quote:
- Users can input stock symbols and receive a quote on the value through fetching from IEX API.

### Buy:
- Users can input a stock symbol and 'buy' them, which will then be added to their portfolio.

### Sell:
- Users can input a stock symbol from their portfolio and 'sell' them.

### Add Cash:
- Users can add cash to their account so that they can buy stocks. If they don't have enough cash, the site rejects the ability to buy.

### History:
- Showcases the entire history of the stocks bought and sold by the user.

### Main:
- Displays the user's portfolio with all the stocks they have and how much their total is.

### Settings:
- Users can see their information such as username and they are able to change their password.
