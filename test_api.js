async function test() {
    console.log("Testing POST /auth/login with krishichoudki");
    const r = await fetch("http://localhost:3000/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: "krishichoudki", password: "123456" })
    });
    console.log("Status:", r.status);
    console.log("Response:", await r.text());
}
test();
