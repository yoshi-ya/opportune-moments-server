const express = require("express");
const cors = require("cors");
const axios = require("axios");
const { MongoClient } = require("mongodb");
const { OpenAI } = require("openai");
const directory = require("./2fa_directory.json");

const dbUri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASSWORD}@cluster0.egjedqq.mongodb.net/?retryWrites=true&w=majority`;
const app = express();
const port = process.env.PORT || 3000;

const logger = (req, res, next) => {
    const timestamp = new Date().toLocaleString();
    const method = req.method;
    const url = req.url;
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

const createCompromisedPwTask = async (email, accounts) => {
    const collection = client.db("app").collection("users");
    try {
        for (const account of accounts) {
            await collection.findOneAndUpdate({ email }, {
                $push: {
                    tasks: {
                        type: "pw",
                        domain: account.domain,
                        state: "PENDING"
                    }
                }
            });
        }
    } catch (err) {
        console.log("Could not create compromised password task.");
    }
};

const initializeUser = async (email) => {
    const collection = client.db("app").collection("users");
    await collection.insertOne({ email });
    const compromisedAccounts = await getCompromisedAccounts(email);
    await createCompromisedPwTask(email, compromisedAccounts);
};

const getNextCompromisedPwTask = async (email) => {
    const collection = client.db("app").collection("users");
    let user;
    try {
        user = await collection.findOne({ email });
    } catch (err) {
        return;
    }
    const now = new Date();
    const lastPwNotificationDate = user.lastPwNotificationDate || now;
    const timeDiff = Math.abs(now - lastPwNotificationDate) / 1000;
    if (!timeDiff > 60 * 60 * 24) {
        return;
    }

    try {
        const tasks = user.tasks;
        const pwTasks = tasks.filter((task) => {
            return task.type === "pw" && task.state === "PENDING";
        });
        if (pwTasks.length > 0) {
            return pwTasks[0];
        }
    } catch (err) {
        return undefined;
    }
};

const updateLastPwNotificationDate = async (email) => {
    const collection = client.db("app").collection("users");
    try {
        await collection.updateOne({ email }, { $set: { lastPwNotificationDate: new Date() } });
    } catch (err) {
        console.log("Could not update last compromised password notification date.");
    }
};

const updateLastPwNotificationState = async (email, domain) => {
    const collection = client.db("app").collection("users");
    try {
        await collection.updateOne({ email, "tasks.domain": domain }, {
            $set: {
                "tasks.$": {
                    type: "pw",
                    domain,
                    state: "FINISHED"
                }
            }
        });
    } catch (err) {
        console.log("Could not update compromised password task state.");
    }
};

const getNextTaskWithoutSurvey = async (domain, email) => {
    try {
        const collection = client.db("app").collection("users");
        const user = await collection.findOne({ email });
        const interactions = user.interactions;
        // sorted from oldest to newest
        const interactionsWithoutSurvey = interactions.filter((interaction) => {
            // if the interaction has no survey and is older than 3 minutes
            return interaction.survey === undefined && Math.abs(interaction.date - new Date()) / 1000 > 60 * 3;
        }).sort((a, b) => a.date - b.date);
        return interactionsWithoutSurvey[0];
    } catch (err) {
        return undefined;
    }
};

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

    if (!user) {
        await initializeUser(userEmail);
    }

    const taskWithoutSurvey = await getNextTaskWithoutSurvey(domain, userEmail);
    if (taskWithoutSurvey) {
        return res.send({ type: taskWithoutSurvey.type, domain: taskWithoutSurvey.domain, survey: true });
    }

    const is2FAvailable = check2FA(domain, userEmail);
    let taskExists;
    if (user && user.interactions) {
        taskExists = user.interactions.find((interaction) => {
            return interaction.domain === domain && interaction.type === "2fa";
        });
    } else {
        taskExists = false;
    }

    if (is2FAvailable && !taskExists) {
        return res.send({ type: "2fa", domain });
    }

    const createdCompromisedPwTask = await getNextCompromisedPwTask(userEmail);
    if (createdCompromisedPwTask) {
        return res.send(createdCompromisedPwTask);
    }

    return res.sendStatus(200);
});

app.get("/instructions/:type/:url", async (req, res) => {
    const type = req.params.type;
    const url = req.params.url;
    const openAiRequestText = type === "pw" ? `Give a very short summary on how to change your password for ${url}` : `Give a very short summary on how to enable 2FA for ${url}`;
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
        await collection.findOne({ email: req.body.email });
    } catch (err) {
        return res.sendStatus(400);
    }

    try {
        await collection.findOneAndUpdate({ email: req.body.email }, {
            $push: {
                interactions: {
                    date: new Date(),
                    type: req.body.taskType,
                    domain: req.body.domain
                }
            }
        });
    } catch (err) {
        console.log("Could not store interaction to DB.");
        return res.sendStatus(400);
    }

    if (req.body.taskType === "pw") {
        await updateLastPwNotificationDate(req.body.email);
        await updateLastPwNotificationState(req.body.email, req.body.domain);
    }

    return res.sendStatus(201);
});

app.post("/survey", async (req, res) => {
    const collection = client.db("app").collection("users");
    let user;
    try {
        user = await collection.findOne({ email: req.body.email });
        const interactions = user.interactions;
        const interaction = interactions.find((interaction) => {
            return interaction.type === req.body.taskType && interaction.domain === req.body.domain && interaction.survey === undefined;
        });
        if (!interaction) {
            return res.sendStatus(400);
        }
        await collection.findOneAndUpdate({ email: req.body.email }, {
            $set: {
                "interactions.$[elem].survey": req.body.survey
            }
        }, {
            arrayFilters: [{ "elem.type": interaction.type, "elem.domain": interaction.domain, "elem.survey": undefined }]
        });
        return res.sendStatus(201);
    } catch (err) {
        console.log(err);
        return res.sendStatus(400);
    }
});

// Start the server and listen on the specified port
app.listen(port, async () => {
    await connectDb();
    console.log(`Server is running on http://localhost:${port}`);
});
