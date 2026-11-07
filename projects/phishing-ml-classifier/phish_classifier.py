#!/usr/bin/env python3
"""Phishing message classifier: multinomial Naive Bayes over word counts.

Usage:
    python3 phish_classifier.py training_data.csv
    python3 phish_classifier.py training_data.csv "your message text here"

Trains on the labeled messages in the CSV, reports accuracy on a
held-out slice, then classifies either the built-in demo messages or
the message you pass. This is the classic first machine learning model
in security work: the same family of math that powered early spam
filters, small enough to explain line by line.
"""

import csv
import math
import re
import sys
from collections import Counter, defaultdict

TOKEN = re.compile(r"[a-z0-9']+")


def tokenize(text):
    return TOKEN.findall(text.lower())


class NaiveBayes:
    def __init__(self):
        self.class_counts = Counter()
        self.word_counts = defaultdict(Counter)
        self.vocab = set()

    def train(self, rows):
        for label, text in rows:
            self.class_counts[label] += 1
            for word in tokenize(text):
                self.word_counts[label][word] += 1
                self.vocab.add(word)

    def log_score(self, label, words):
        total_docs = sum(self.class_counts.values())
        total_words = sum(self.word_counts[label].values())
        vocab_size = len(self.vocab)
        score = math.log(self.class_counts[label] / total_docs)
        for word in words:
            count = self.word_counts[label][word]
            score += math.log((count + 1) / (total_words + vocab_size))
        return score

    def predict(self, text):
        words = tokenize(text)
        scores = {label: self.log_score(label, words) for label in self.class_counts}
        best = max(scores, key=scores.get)
        diff = abs(scores["phish"] - scores["legit"]) if set(scores) == {"phish", "legit"} else 0.0
        confidence = 1 / (1 + math.exp(-diff))
        return best, confidence, scores


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 phish_classifier.py <training_data.csv> [message]")
        return 2
    with open(sys.argv[1], newline="") as handle:
        rows = [(r["label"], r["text"]) for r in csv.DictReader(handle)]
    holdout = rows[::4]
    train = [row for i, row in enumerate(rows) if i % 4 != 0]
    model = NaiveBayes()
    model.train(train)
    correct = sum(1 for label, text in holdout if model.predict(text)[0] == label)
    print(f"Training messages: {len(train)}  Held out for testing: {len(holdout)}")
    print(f"Held-out accuracy: {correct}/{len(holdout)} = {correct / len(holdout):.0%}")
    full = NaiveBayes()
    full.train(rows)
    demos = [
        "Urgent verify your account now your password expires today click the link",
        "The staff meeting is moved to Thursday please bring the updated schedule",
    ]
    targets = [sys.argv[2]] if len(sys.argv) > 2 else demos
    for text in targets:
        label, confidence, _ = full.predict(text)
        print(f"\nMessage: {text}")
        print(f"Prediction: {label.upper()} (confidence {confidence:.0%})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
