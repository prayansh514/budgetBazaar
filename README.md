
# Project Overview

BudgetBazaar is an e-commerce web application that allows users to browse, select, and purchase products online. It's built with a modern, scalable tech stack to ensure a smooth shopping experience and secure payment processing.




## Tech Stack used

Frontend: React js

Backend: Node.js, Express.js

Database:

MongoDB: Primary data storage for users, products, orders.

Redis: In-memory caching for sessions, hot data, and rate-limiting.

Payments: Stripe.js for secure payment processing

Authentication: JSON Web Tokens (JWT)
## Setup .env file in root folder


PORT=5000

MONGO_URI=your_mongo_uri

UPSTASH_REDIS_URL=your_redis_url

ACCESS_TOKEN_SECRET=your_access_token_secret
REFRESH_TOKEN_SECRET=your_refresh_token_secret

CLOUDINARY_CLOUD_NAME=your_cloud_name
CLOUDINARY_API_KEY=your_api_key
CLOUDINARY_API_SECRET=your_api_secret

STRIPE_SECRET_KEY=your_stripe_secret_key
CLIENT_URL=http://localhost:5173

NODE_ENV=development

## Run this app locally

    npm run build
## Run this app locally

    npm run build
## Start the app

    npm run start
### 🎥 Demo Video

As you cannot become an admin on the deployed website you have to use your own env variables and start it locally but here is the admin view you will get once you have an admin access

[▶️ Watch Admin View Demo (Google Drive)](https://drive.google.com/file/d/17KFXWIyqjF8b906VXA8eX1mN2N8PGRhC/preview)

Incase the deployed website is saying bad request or too many requests please wait for some time and try again

here is the demo video of the working deployed website

[▶️ Watch Demo (Google Drive)](https://drive.google.com/file/d/1gYkSSJnvf9oUCadKWiDmvFMcS8_uorSw/preview)

    
## Deployed website link

    https://budgetbazaar-1.onrender.com
## Alternate Website link

Incase the above link is showing 502 error or too many requests here is an alternate website where i have deployed the project

    https://budgetbazaar-3.onrender.com/

## Information

As this is a test application please put in the card no during checkout as 4242 4242 4242 4242   and cv as 424
