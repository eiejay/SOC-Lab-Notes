# Phishing Classifier: My First Naive Bayes Model

I kept running into the same wall with rule based detection: every rule I wrote caught yesterday's phish. So I built the smallest machine learning model that actually learns, a multinomial Naive Bayes classifier, and trained it on messages instead of hand writing patterns. It is the companion to the header analyzer in this repo: that one checks the envelope, this one learns from the words. Real filters layer both, which is exactly what I wanted to understand.

## Run it

    python3 phish_classifier.py training_data.csv
    python3 phish_classifier.py training_data.csv "any message text to score"

## What I got

    Training messages: 19  Held out for testing: 7
    Held-out accuracy: 5/7 = 71%

    Message: Urgent verify your account now your password expires today click the link
    Prediction: PHISH (confidence 100%)

    Message: The staff meeting is moved to Thursday please bring the updated schedule
    Prediction: LEGIT (confidence 100%)

71 percent sounds weak until you see the training set: 26 short messages I wrote by hand. The model had almost nothing to learn from and still separated most of the test set. That was the lesson for me: the math is not the hard part, the data is.

## How it works, the way I explain it to myself

1. Training: split every labeled message into words and count how often each word shows up in phish versus in normal mail.
2. Scoring: a new message gets scored under both classes. Each word adds the log of its smoothed probability, plus how common the class is overall. Smoothing (adding one to every count) keeps a word the model has never seen from wiping out the whole score.
3. Higher score wins. The confidence number is the gap between the two scores pushed through a logistic curve. On short messages it pegs at 100 percent fast, so I trust the ranking more than the number.

## What I would tell anyone copying this

- A word model is easy to dodge: an image only phish, or one written to avoid common words, walks past it. Layer it or do not bother.
- The reason I still like this model for security work: it can always explain itself. The score is a pile of per word contributions, so when it flags something, I can point at the exact words that did it. Try getting that out of a neural network in an incident call.
- Give it real data and it gets serious fast. My 26 messages are a teaching set, and I kept them small on purpose: the whole model fits in your head, which was the goal.
