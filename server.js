const express = require("express");
const cors = require("cors");
const axios = require("axios");
const { MongoClient } = require("mongodb");
const { OpenAI } = require("openai");
const { encrypt, decrypt } = require("./crypto");
const directory = require("./2fa_directory.json");

const dbUri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASSWORD}@cluster0.egjedqq.mongodb.net/?retryWrites=true&w=majority`;
const app = express();
const port = process.env.PORT || 3000;

const logger = (req, res, next) => {
    const timestamp = new Date().toLocaleString();
    const method = req.method;
    const url = req.url.substring(0, 13);
    console.log(`[${timestamp}] ${method} ${url}`);
    next();
};
// middleware
app.use(cors());
app.use(logger);
app.use(express.json());

const client = new MongoClient(dbUri, {});
const openai = new OpenAI();

const connectDb = async () => {
    try {
        await client.connect();
        console.log("Database connected.");
    } catch (error) {
        console.log("Could not connect to DB.");
        await client.close();
    }
};

const check2FA = (domain) => {
    let isAvailable = directory.some((entry) => {
        return domain.includes(entry[1].domain);
    });
    if (!isAvailable) {
        isAvailable = directory.some((entry) => {
            if (!entry[1]["additional-domains"]) return false;
            return entry[1]["additional-domains"].some((additionalDomain) => {
                return domain.includes(additionalDomain);
            });
        });
    }
    return isAvailable;
};

const getCompromisedAccounts = async (email) => {
    const url = `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}`;
    const headers = {
        headers: {
            "hibp-api-key": process.env.HIBP_API_KEY,
            "Content-Type": "application/json"
        },
        params: {
            truncateResponse: "false"
        }
    };

    const breaches = [];
    try {
        const response = await axios.get(url, headers);
        if (response.status !== 404) {
            for (const breach of response.data) {
                breaches.push({ name: breach.Name, domain: breach.Domain });
            }
        }
    } catch (error) {
        return [];
    }
    return breaches;
};

const createCompromisedPwTask = async (email, accountEmail, accounts) => {
    const collection = client.db("app").collection("users");
    try {
        for (const account of accounts) {
            const encryptedDomain = encrypt(account.domain);
            await collection.findOneAndUpdate({ email }, {
                $push: {
                    tasks: {
                        type: "pw",
                        domain: encryptedDomain,
                        account: encrypt(accountEmail)
                    }
                }
            });
        }
    } catch (err) {
        console.log("Could not create compromised password task.");
    }
};

const createTwoFaTask = async (email, domain) => {
    const collection = client.db("app").collection("users");
    const user = await collection.findOne({ email });
    let taskExists = false;
    if (user.tasks) {
        taskExists = user.tasks.find((task) => {
            return decrypt(task.domain) === domain && task.type === "2fa";
        });
    }

    if (taskExists) {
        return;
    }

    try {
        await collection.findOneAndUpdate({ email }, {
            $push: {
                tasks: {
                    type: "2fa",
                    domain: encrypt(domain)
                }
            }
        });
    } catch (err) {
        console.log("Could not create 2FA task.");
    }
};

const initializeUser = async (email) => {
    const collection = client.db("app").collection("users");
    await collection.insertOne({ email, initial: true });
    await updateLastAccessDate(email);
    const compromisedAccounts = await getCompromisedAccounts(email);
    await createCompromisedPwTask(email, email, compromisedAccounts);
};

const updateLastAccessDate = async (email) => {
    const collection = client.db("app").collection("users");
    try {
        await collection.updateOne({ email }, { $set: { lastAccessDate: new Date().toLocaleString() } });
    } catch (err) {
        console.log("Could not update last compromised password notification date.");
    }
};

const getNextTaskWithoutSurvey = async (domain, email) => {
    try {
        const collection = client.db("app").collection("users");
        const user = await collection.findOne({ email });
        const now = new Date().toLocaleString();
        const lastSurveyDate = user.lastSurveyDate;
        // if last survey was not more than 1 minutes ago
        if (lastSurveyDate && Math.abs(new Date().getTime() - new Date(lastSurveyDate).getTime()) / 1000 < 60) {
            return undefined;
        }
        const interactionsWithoutSurvey = user.interactions.filter((interaction) => {
            // if the interaction has no survey and is older than 10 minutes
            return interaction.survey === undefined && Math.abs(new Date(interaction.date).getTime() - new Date(now).getTime()) / 1000 > 60 * 10;
        }).sort((a, b) => a.date - b.date);
        if (interactionsWithoutSurvey.length === 0) {
            return undefined;
        }
        const task = interactionsWithoutSurvey[0];
        // set lastSurveyDate for user (fixes multiple survey popups on different tabs)
        await collection.findOneAndUpdate({ email }, {
            $set: {
                lastSurveyDate: new Date().toLocaleString()
            }
        });
        return {
            type: task.type,
            domain: decrypt(task.domain),
            affirmative: task.affirmative,
            survey: true
        };
    } catch (err) {
        return undefined;
    }
};

async function getNextTask (userEmail) {
    const collection = client.db("app").collection("users");
    try {
        const user = await collection.findOne({ email: userEmail });
        const tasks = user.tasks || [];
        const lastNotificationDate = user.lastNotificationDate;
        const now = new Date().toLocaleString();
        // if there are no tasks or the last notification was less than 1 hour ago
        const isRelevant = !lastNotificationDate || (lastNotificationDate && Math.abs(new Date(now).getTime() - new Date(lastNotificationDate).getTime()) / 1000 > 60 * 60);
        const interactions = user.interactions || [];
        // filter out tasks that are already in interactions
        const relevantTasks = tasks.filter((task) => {
            return !interactions.find((interaction) => {
                return interaction.type === task.type && decrypt(interaction.domain) === decrypt(task.domain);
            });
        });
        if (relevantTasks.length === 0 || !isRelevant) {
            return undefined;
        }
        const randomIndex = Math.floor(Math.random() * relevantTasks.length);
        const task = relevantTasks[randomIndex];
        await collection.findOneAndUpdate({ email: userEmail }, {
            $set: {
                lastNotificationDate: new Date().toLocaleString()
            }
        });
        return {
            type: task.type,
            domain: decrypt(task.domain),
            account: decrypt(task.account) || undefined
        };
    } catch (err) {
        return undefined;
    }
}

// routes
app.get("/", async (req, res) => {
    res.sendStatus(200);
});

app.post("/popup", async (req, res) => {
    const collection = client.db("app").collection("users");
    const userEmail = req.body.email;
    if (!userEmail) {
        return res.sendStatus(400);
    }

    const domain = new URL(req.body.url).hostname;

    let user;
    try {
        user = await collection.findOne({ email: userEmail });
    } catch (err) {
        user = undefined;
    }

    if (user) {
        const lastAccessDate = user.lastAccessDate;
        // if last access was less than 5min ago
        if (lastAccessDate && Math.abs(new Date().getTime() - new Date(lastAccessDate).getTime()) / 1000 < 60 * 5) {
            return res.sendStatus(204);
        }
        await updateLastAccessDate(userEmail);
    }

    if (!user) {
        await initializeUser(userEmail);
    }

    if (!user || user.initial) {
        return res.send({ initial: true });
    }
    const taskWithoutSurvey = await getNextTaskWithoutSurvey(domain, userEmail);
    if (taskWithoutSurvey) {
        return res.send(taskWithoutSurvey);
    }

    const is2FAvailable = check2FA(domain, userEmail);
    if (is2FAvailable) {
        await createTwoFaTask(userEmail, domain);
    }

    const nextTask = await getNextTask(userEmail);
    if (nextTask) {
        return res.send(nextTask);
    }

    res.sendStatus(204);
});

app.get("/instructions/:type/:url", async (req, res) => {
    const url = req.params.url;
    const openAiRequestText = `Give a very short summary on how to enable 2FA for ${url}`;
    const completion = await openai.chat.completions.create({
        messages: [{ role: "system", content: openAiRequestText }],
        model: "gpt-3.5-turbo"
    });
    const instructions = completion.choices[0].message?.content;
    res.send({ data: instructions });
});

app.post("/interaction", async (req, res) => {
    const collection = client.db("app").collection("users");
    try {
        await collection.findOneAndUpdate({ email: req.body.email }, {
            $push: {
                interactions: {
                    date: new Date().toLocaleString(),
                    type: req.body.taskType,
                    domain: encrypt(req.body.domain),
                    affirmative: req.body.affirmative
                }
            }
        });
    } catch (err) {
        return res.sendStatus(400);
    }
    return res.sendStatus(201);
});

app.post("/survey", async (req, res) => {
    const collection = client.db("app").collection("users");
    let user;
    try {
        user = await collection.findOne({ email: req.body.email });
        const interaction = user.interactions.find((interaction) => {
            return interaction.type === req.body.taskType && decrypt(interaction.domain) === req.body.domain && interaction.survey === undefined;
        });
        if (!interaction) {
            return res.sendStatus(400);
        }

        await collection.findOneAndUpdate({ email: req.body.email }, {
            $set: {
                "interactions.$[elem].survey": req.body.survey
            }
        }, {
            arrayFilters: [{
                "elem.type": interaction.type,
                "elem.domain": interaction.domain,
                "elem.survey": undefined
            }]
        });
        return res.sendStatus(201);
    } catch (err) {
        return res.sendStatus(400);
    }
});

app.post("/email", async (req, res) => {
    const collection = client.db("app").collection("users");
    const emails = req.body.emails;
    if (!emails) {
        return res.sendStatus(400);
    }
    try {
        await collection.findOneAndUpdate({ email: req.body.email }, {
            $set: {
                initial: false
            }
        });
        // create compromised password tasks
        for (const email of emails) {
            const compromisedAccounts = await getCompromisedAccounts(email);
            await createCompromisedPwTask(req.body.email, email, compromisedAccounts);
        }
        return res.sendStatus(201);
    } catch (err) {
        return res.sendStatus(400);
    }
});

// Start the server and listen on the specified port
app.listen(port, async () => {
    await connectDb();
    console.log(`Server is running on http://localhost:${port}`);
});
